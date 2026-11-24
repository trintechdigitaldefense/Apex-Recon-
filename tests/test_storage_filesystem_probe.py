import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE = REPO_ROOT / "tools" / "apex_storage_probe.py"


class StorageFilesystemProbeTests(unittest.TestCase):
    def test_probe_reports_capabilities_and_cleans_its_temporary_directory(self):
        with tempfile.TemporaryDirectory(prefix="apexrecon-probe-test-") as parent:
            before = set(Path(parent).iterdir())
            result = subprocess.run(
                [sys.executable, str(PROBE), "--parent", parent],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertIn(result.returncode, (0, 1), result.stderr)
            report = json.loads(result.stdout)
            self.assertIn("hard_links", report)
            self.assertIn("directory_fsync", report)
            self.assertIn("atomic_publication", report)
            self.assertFalse(report["network_access"])
            self.assertFalse(report["existing_files_modified"])
            self.assertTrue(report["temporary_artifacts_removed"])
            self.assertEqual(set(Path(parent).iterdir()), before)

    def test_probe_rejects_nonexistent_parent_without_creating_it(self):
        with tempfile.TemporaryDirectory(prefix="apexrecon-probe-parent-") as parent:
            missing = Path(parent) / "does-not-exist"
            result = subprocess.run(
                [sys.executable, str(PROBE), "--parent", str(missing)],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertIn("probe_error", report)
            self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
