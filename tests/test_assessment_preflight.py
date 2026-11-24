"""Offline tests for Phase 2AP assessment preflight enforcement."""
import unittest
from unittest.mock import Mock, patch

import apex_recon_v2 as apex


def ready_report():
    return {
        "python": {"supported": True},
        "project": {"complete": True, "writable": True},
        "storage": {"checked": True, "compatible": True},
    }


class AssessmentPreflightTests(unittest.TestCase):
    def test_compatible_environment_passes(self):
        result = apex.assessment_preflight(ready_report)
        self.assertEqual(result, {"ready": True, "reasons": []})

    def test_unverified_or_incompatible_storage_blocks(self):
        for storage in (
            {"checked": False, "compatible": False},
            {"checked": True, "compatible": False},
            {"checked": True, "compatible": None},
        ):
            with self.subTest(storage=storage):
                report = ready_report()
                report["storage"] = storage
                result = apex.assessment_preflight(lambda: report)
                self.assertFalse(result["ready"])
                self.assertTrue(any("Atomic evidence storage" in item for item in result["reasons"]))

    def test_incomplete_project_and_unwritable_artifact_directory_block(self):
        report = ready_report()
        report["project"] = {"complete": False, "writable": False}
        result = apex.assessment_preflight(lambda: report)
        self.assertFalse(result["ready"])
        self.assertEqual(len(result["reasons"]), 2)

    def test_unsupported_python_blocks(self):
        report = ready_report()
        report["python"]["supported"] = False
        result = apex.assessment_preflight(lambda: report)
        self.assertFalse(result["ready"])
        self.assertTrue(any("Python runtime" in item for item in result["reasons"]))

    def test_preflight_failure_prevents_runner_execution(self):
        runner = Mock()
        report = ready_report()
        report["storage"]["compatible"] = False
        with patch("builtins.print"), patch("builtins.input", return_value=""):
            executed = apex.run_assessment_with_preflight(runner, lambda: report)
        self.assertFalse(executed)
        runner.assert_not_called()

    def test_preflight_exception_fails_closed_and_prevents_runner(self):
        runner = unittest.mock.Mock()

        def broken_diagnostics():
            raise OSError("synthetic probe failure")

        with patch("builtins.print"), patch("builtins.input", return_value=""):
            executed = apex.run_assessment_with_preflight(runner, broken_diagnostics)
        self.assertFalse(executed)
        runner.assert_not_called()

    def test_successful_preflight_runs_module_once(self):
        runner = unittest.mock.Mock()
        executed = apex.run_assessment_with_preflight(runner, ready_report)
        self.assertTrue(executed)
        runner.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
