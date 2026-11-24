import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_doctor.py"
SPEC = importlib.util.spec_from_file_location("apex_doctor", MODULE_PATH)
doctor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(doctor)


class ApexDoctorTests(unittest.TestCase):
    def setUp(self):
        self.tools = {"dig", "whois", "curl", "nmap", "ip"}
        self.packages = {"reportlab", "cryptography", "pip", "venv"}

    def lookup_tool(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def lookup_package(self, name):
        return name in self.packages

    def diagnose(self, **kwargs):
        return doctor.collect_diagnostics(
            executable_lookup=self.lookup_tool,
            module_lookup=self.lookup_package,
            **kwargs,
        )

    def test_supported_python_and_all_capabilities(self):
        report = self.diagnose(python_version=(3, 12, 1))
        self.assertTrue(report["python"]["supported"])
        self.assertTrue(all(report["capabilities"].values()))

    def test_python_below_minimum_is_unsupported(self):
        report = self.diagnose(python_version=(3, 9, 18))
        self.assertFalse(report["python"]["supported"])
        self.assertEqual(report["python"]["minimum"], "3.10")

    def test_http_tls_does_not_depend_on_external_tools(self):
        self.tools.clear()
        self.packages.clear()
        report = self.diagnose(python_version=(3, 12, 0))
        self.assertTrue(report["capabilities"]["http_tls_assessment"])
        self.assertFalse(report["capabilities"]["dns_lookup"])
        self.assertFalse(report["capabilities"]["smb_assessment"])
        self.assertFalse(report["capabilities"]["pdf_export"])
        self.assertFalse(report["capabilities"]["evidence_signing"])

    def test_missing_tool_is_reported_by_capability(self):
        self.tools.remove("nmap")
        report = self.diagnose(python_version=(3, 12, 0))
        self.assertFalse(report["capabilities"]["external_port_scan"])
        self.assertFalse(report["capabilities"]["smb_assessment"])

    def test_missing_optional_python_packages_are_not_core_failures(self):
        self.packages.clear()
        report = self.diagnose(python_version=(3, 12, 0))
        self.assertTrue(report["python"]["supported"])
        self.assertFalse(report["capabilities"]["pdf_export"])
        self.assertFalse(report["capabilities"]["evidence_signing"])

    def test_termux_install_guidance(self):
        self.tools.clear()
        report = self.diagnose(
            python_version=(3, 12, 0),
            system="Linux",
            prefix="/data/data/com.termux/files/usr",
        )
        output = doctor.render_report(report)
        self.assertIn("pkg install dnsutils", output)
        self.assertIn("pkg install nmap", output)

    def test_linux_install_guidance(self):
        self.tools.clear()
        report = self.diagnose(
            python_version=(3, 12, 0), system="Linux", prefix="/usr"
        )
        output = doctor.render_report(report)
        self.assertIn("apt-get install -y dnsutils", output)
        self.assertIn("apt-get install -y iproute2", output)

    def test_json_mode_outputs_parseable_diagnostics(self):
        stream = io.StringIO()
        stub = {
            "python": {"version": "3.12.0", "supported": True, "minimum": "3.10"},
            "platform": {"system": "Linux", "termux": False},
            "environment": {"executable": "python3", "virtual_environment": True,
                            "pip_available": True, "venv_available": True},
            "project": {"root": ".", "required_files": {}, "complete": True,
                        "writable": True, "write_error": None},
            "tools": {}, "python_packages": {}, "capabilities": {},
        }
        with patch.object(doctor, "collect_diagnostics", return_value=stub):
            with contextlib.redirect_stdout(stream):
                result = doctor.main(["--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stream.getvalue())["python"]["version"], "3.12.0")

    def test_strict_mode_fails_when_dependencies_are_missing(self):
        self.tools.clear()
        self.packages.clear()
        with patch.object(doctor, "collect_diagnostics", return_value=self.diagnose(
            python_version=(3, 12, 0)
        )):
            with contextlib.redirect_stdout(io.StringIO()):
                result = doctor.main(["--strict"])
        self.assertEqual(result, 1)

    def test_normal_mode_allows_partial_capability_installation(self):
        self.tools.clear()
        self.packages.clear()
        with patch.object(doctor, "collect_diagnostics", return_value=self.diagnose(
            python_version=(3, 12, 0)
        )):
            with contextlib.redirect_stdout(io.StringIO()):
                result = doctor.main([])
        self.assertEqual(result, 0)

    def test_project_layout_reports_missing_core_files(self):
        with tempfile.TemporaryDirectory() as directory:
            report = doctor.inspect_project(directory, artifact_directory=directory)
        self.assertFalse(report["complete"])
        self.assertTrue(report["writable"])
        self.assertTrue(all(not present for present in report["required_files"].values()))

    def test_project_layout_requires_atomic_storage_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in doctor.REQUIRED_PROJECT_FILES:
                if name != "apex_storage.py":
                    (root / name).touch()
            report = doctor.inspect_project(root, artifact_directory=root)
        self.assertFalse(report["complete"])
        self.assertFalse(report["required_files"]["apex_storage.py"])

    def test_project_write_probe_leaves_no_temporary_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            report = doctor.inspect_project(directory)
            leftovers = list(Path(directory).glob(".apexrecon-write-check-*"))
        self.assertTrue(report["writable"])
        self.assertEqual(leftovers, [])

    def test_project_write_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(doctor.tempfile, "NamedTemporaryFile",
                              side_effect=PermissionError("read only")):
                report = doctor.inspect_project(directory)
        self.assertFalse(report["writable"])
        self.assertEqual(report["write_error"], "PermissionError")

    def test_virtual_environment_detection(self):
        report = self.diagnose(
            python_version=(3, 12, 0),
            python_prefix="/project/.venv",
            python_base_prefix="/usr",
        )
        self.assertTrue(report["environment"]["virtual_environment"])

    def test_report_explains_same_interpreter_and_storage_checks(self):
        report = self.diagnose(python_version=(3, 12, 0))
        output = doctor.render_report(report)
        self.assertIn("Artifact directory write test: WRITABLE", output)
        self.assertIn("same Python interpreter", output)
        self.assertIn("source .venv/bin/activate", output)


if __name__ == "__main__":
    unittest.main()
