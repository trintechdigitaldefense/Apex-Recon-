"""Regression tests for filesystem capability probing on reduced Python builds."""
import os
from pathlib import Path
import tempfile
import unittest

from tools import apex_storage_probe


class StorageProbeCompatibilityTests(unittest.TestCase):
    def test_missing_os_link_is_reported_without_crashing(self):
        if not hasattr(os, "link"):
            original_link = None
        else:
            original_link = os.link

        with tempfile.TemporaryDirectory() as directory:
            try:
                if original_link is not None:
                    delattr(os, "link")
                report = apex_storage_probe.probe(Path(directory))
            finally:
                if original_link is not None:
                    os.link = original_link

        self.assertIs(report["hard_links"]["supported"], False)
        self.assertIn("AttributeError", report["hard_links"]["error"])
        self.assertIs(report["atomic_publication"]["supported"], False)
        self.assertIn("AttributeError", report["atomic_publication"]["error"])
        self.assertIs(report["overall_atomic_storage_compatible"], False)
        self.assertIs(report["temporary_artifacts_removed"], True)


if __name__ == "__main__":
    unittest.main()
