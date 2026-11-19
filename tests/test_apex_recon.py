import importlib.util
import tempfile
import stat
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_recon_v2.py"
SPEC = importlib.util.spec_from_file_location("apex_recon_v2", MODULE_PATH)
apex = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(apex)


class TargetValidationTests(unittest.TestCase):
    def test_valid_dns_hostname_and_ip(self):
        self.assertTrue(apex.validate_osint_target("example.com"))
        self.assertTrue(apex.validate_osint_target("sub.example.co.tt"))
        self.assertTrue(apex.validate_osint_target("192.0.2.10"))

    def test_rejects_urls_paths_and_malformed_hostnames(self):
        for value in ("https://example.com", "example.com/path", "-bad.example", "bad..example", "bad host"):
            with self.subTest(value=value):
                self.assertFalse(apex.validate_osint_target(value))

    def test_network_target_accepts_ip_and_bounded_cidr(self):
        self.assertTrue(apex.validate_network_target("192.168.10.5"))
        self.assertTrue(apex.validate_network_target("192.168.10.0/23"))

    def test_network_target_rejects_hostnames_and_unbounded_ranges(self):
        for value in ("example.com", "0.0.0.0/0", "192.168.0.0/16", "not-a-network"):
            with self.subTest(value=value):
                self.assertFalse(apex.validate_network_target(value))


class SMBParserTests(unittest.TestCase):
    def test_parses_host_ports_signing_and_vulnerability(self):
        sample = """Nmap scan report for fileserver.example (192.0.2.8)
445/tcp open microsoft-ds
| smb-security-mode:
|   message_signing: disabled
| smb-vuln-ms17-010:
|   VULNERABLE:
"""
        hosts = apex.parse_smb_output(sample)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host["ip"], "192.0.2.8")
        self.assertEqual(host["hostname"], "fileserver.example")
        self.assertIn("445/tcp microsoft-ds", host["open_ports"])
        self.assertEqual(host["signing"], "DISABLED")
        self.assertTrue(host["vuln_ms17010"])
        self.assertEqual(host["vuln_ms17010_status"], "INDICATOR")
        self.assertEqual(host["risk_level"], "HIGH")
        self.assertIn("independently verify", host["findings"][0].lower())
        self.assertNotIn("remote code execution", host["findings"][0].lower())

    def test_does_not_flag_not_vulnerable_status(self):
        sample = """Nmap scan report for fileserver.example (192.0.2.9)
445/tcp open microsoft-ds
| smb-vuln-ms17-010:
|   State: NOT VULNERABLE
"""
        hosts = apex.parse_smb_output(sample)
        self.assertEqual(len(hosts), 1)
        self.assertFalse(hosts[0]["vuln_ms17010"])
        self.assertEqual(hosts[0]["vuln_ms17010_status"], "NOT_VULNERABLE")
        self.assertEqual(hosts[0]["risk_level"], "LOW")

    def test_missing_vulnerability_script_result_is_not_reported_as_clean(self):
        sample = """Nmap scan report for fileserver.example (192.0.2.10)
445/tcp open microsoft-ds
| smb-vuln-ms17-010:
"""
        hosts = apex.parse_smb_output(sample)
        self.assertEqual(hosts[0]["vuln_ms17010_status"], "NOT_REPORTED")
        self.assertFalse(hosts[0]["vuln_ms17010"])
        self.assertEqual(hosts[0]["risk_level"], "LOW")

    def test_likely_vulnerable_is_only_a_potential_indicator(self):
        sample = """Nmap scan report for fileserver.example (192.0.2.11)
445/tcp open microsoft-ds
| smb-vuln-ms17-010:
|   State: LIKELY VULNERABLE
"""
        hosts = apex.parse_smb_output(sample)
        self.assertEqual(hosts[0]["vuln_ms17010_status"], "POTENTIAL")
        self.assertEqual(hosts[0]["risk_level"], "MEDIUM")

    def test_disabled_signing_uses_medium_risk_classification(self):
        sample = """Nmap scan report for fileserver.example (192.0.2.12)
445/tcp open microsoft-ds
| smb-security-mode:
|   message_signing: disabled
"""
        hosts = apex.parse_smb_output(sample)
        self.assertEqual(hosts[0]["signing"], "DISABLED")
        self.assertEqual(hosts[0]["risk_level"], "MEDIUM")


class CommandExecutionTests(unittest.TestCase):
    @patch.object(apex.subprocess, "run")
    def test_run_cmd_uses_safe_subprocess_options(self, mocked_run):
        mocked_run.return_value = type("Completed", (), {"stdout": "ok\n", "stderr": ""})()
        stdout, stderr = apex.run_cmd(["echo", "ok"], timeout=3)
        self.assertEqual(stdout, "ok")
        self.assertEqual(stderr, "")
        kwargs = mocked_run.call_args.kwargs
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["stdin"], apex.subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 3.0)

    @patch.object(apex.subprocess, "run")
    def test_run_cmd_rejects_string_command(self, mocked_run):
        self.assertEqual(apex.run_cmd("echo unsafe"), ("", "INVALID_COMMAND"))
        mocked_run.assert_not_called()

    @patch.object(apex.subprocess, "run")
    def test_run_cmd_rejects_non_finite_and_excessive_timeouts(self, mocked_run):
        for timeout in (float("nan"), float("inf"), float("-inf"), 601):
            with self.subTest(timeout=timeout):
                self.assertEqual(apex.run_cmd(["echo", "ok"], timeout=timeout), ("", "INVALID_TIMEOUT"))
        mocked_run.assert_not_called()

    @patch.object(apex.subprocess, "run")
    def test_run_cmd_rejects_non_list_command(self, mocked_run):
        self.assertEqual(apex.run_cmd({"echo": "ok"}), ("", "INVALID_COMMAND"))
        mocked_run.assert_not_called()

    @patch.object(apex.subprocess, "run")
    def test_run_cmd_handles_missing_dependency(self, mocked_run):
        mocked_run.side_effect = FileNotFoundError
        self.assertEqual(apex.run_cmd(["missing-tool"]), ("", "NOT_FOUND:missing-tool"))


class NetworkDiscoveryTests(unittest.TestCase):
    @patch.object(apex, "run_cmd")
    def test_subnet_detection_preserves_real_prefix(self, mocked_run):
        mocked_run.return_value = (
            "192.168.4.0/23 dev wlan0 proto kernel scope link src 192.168.4.12",
            "",
        )
        self.assertEqual(apex.get_local_subnet(), ("192.168.4.0/23", "192.168.4.12"))


class AuthorizationTests(unittest.TestCase):
    @patch("builtins.input", return_value="YES")
    def test_authorization_requires_exact_yes(self, mocked_input):
        self.assertTrue(apex.confirm_authorized_scope("192.168.1.0/24"))

    @patch("builtins.input", return_value="yes")
    def test_lowercase_yes_does_not_confirm(self, mocked_input):
        self.assertFalse(apex.confirm_authorized_scope("192.168.1.0/24"))


class ReportSafetyTests(unittest.TestCase):
    def test_report_escapes_untrusted_scan_values(self):
        malicious = '<img src=x onerror="alert(1)">'
        host = {
            "ip": "192.0.2.10",
            "hostname": malicious,
            "os": malicious,
            "shares": [malicious],
            "signing": "Unknown",
            "vuln_ms17010": False,
            "vuln_ms10054": False,
            "open_ports": [malicious],
            "risk_level": "LOW",
            "findings": [malicious],
        }
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(apex, "REPORT_FILE", str(Path(directory) / "report_{}.html")):
                path = apex.generate_html_report([host], malicious, 0.1, module_name=malicious)
                report = Path(path).read_text(encoding="utf-8")
                report_mode = stat.S_IMODE(Path(path).stat().st_mode)
        self.assertNotIn('<img src=x', report)
        self.assertIn("&lt;img", report)
        self.assertNotIn('onerror="alert(1)"', report)
        self.assertNotIn("fonts.googleapis.com", report)
        self.assertIn("NOT TESTED / NO RESULT", report)
        self.assertIn("Low-Risk Hosts", report)
        self.assertEqual(report_mode, 0o600)

    def test_log_file_is_created_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "apex_recon.log"
            with patch.object(apex, "LOG_FILE", str(log_path)):
                apex.log("private test record")
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)
            self.assertIn("private test record", log_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
