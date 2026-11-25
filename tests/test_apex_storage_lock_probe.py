"""Filesystem advisory-lock probe regression tests."""
import tempfile
import unittest
from pathlib import Path

from tools.apex_storage_probe import probe


class AdvisoryFileLockProbeTests(unittest.TestCase):
    def test_probe_confirms_cross_process_exclusive_lock_and_release(self):
        with tempfile.TemporaryDirectory() as directory:
            report = probe(Path(directory))

            locking = report["advisory_file_locking"]
            self.assertTrue(locking["supported"], locking["error"])
            self.assertTrue(locking["exclusive_lock_blocks_other_process"])
            self.assertTrue(locking["lock_released_for_waiting_process"])
            self.assertTrue(report["temporary_artifacts_removed"])

    def test_probe_reports_locking_as_a_separate_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            report = probe(Path(directory))

            self.assertIn("advisory_file_locking", report)
            self.assertIn("overall_atomic_storage_compatible", report)
            self.assertTrue(report["overall_atomic_storage_compatible"])


if __name__ == "__main__":
    unittest.main()
