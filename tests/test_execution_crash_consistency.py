"""Process-crash consistency tests for execution journals and module sidecars.

All child processes use synthetic local data. No assessment runner or target is invoked.
"""
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apex_execution import (
    ExecutionJournal, MODULES, inspect_execution_journal,
    inspect_execution_recovery,
)

ROOT = Path(__file__).resolve().parents[1]


class ExecutionCrashConsistencyTests(unittest.TestCase):
    def _started_journal(self, directory):
        path = Path(directory) / "execution.jsonl"
        journal = ExecutionJournal.create(path, "crash-test-execution", [MODULES[0]])
        journal.start_module(MODULES[0])
        return path, journal

    def _child(self, source, path):
        return subprocess.run(
            [sys.executable, "-c", source, str(path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    def test_crash_during_sidecar_staging_never_exposes_final_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal = self._started_journal(directory)
            before = path.read_bytes()
            source = r"""
import os, sys
from pathlib import Path
import apex_storage
from apex_execution import ExecutionJournal, MODULES
path = Path(sys.argv[1])
def crash_before_file_sync(_fd):
    os._exit(71)
apex_storage.os.fsync = crash_before_file_sync
journal = ExecutionJournal(path, "crash-test-execution")
journal.finish_module(MODULES[0], "COMPLETED", {"status": "COMPLETED", "findings": []})
"""
            result = self._child(source, path)
            self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(inspect_execution_journal(path)["valid"])
            self.assertEqual(
                inspect_execution_recovery(path)["modules"][0]["artifact_status"],
                "INTERRUPTED",
            )
            self.assertEqual(list(Path(directory).glob("*_module_1.json")), [])
            self.assertEqual(len(list(Path(directory).glob(".apexrecon-tmp-*"))), 1)

    def test_crash_after_sidecar_publication_leaves_only_an_unreferenced_orphan(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal = self._started_journal(directory)
            journal_before = path.read_bytes()
            source = r"""
import os, sys
from pathlib import Path
from apex_execution import ExecutionJournal, MODULES
path = Path(sys.argv[1])
original = ExecutionJournal._append
def stop_before_completion_event(self, event_type, *args, **kwargs):
    if event_type == "MODULE_FINISHED":
        os._exit(72)
    return original(self, event_type, *args, **kwargs)
ExecutionJournal._append = stop_before_completion_event
journal = ExecutionJournal(path, "crash-test-execution")
journal.finish_module(MODULES[0], "COMPLETED", {"status": "COMPLETED", "findings": []})
"""
            result = self._child(source, path)
            self.assertEqual(result.returncode, 72, result.stdout + result.stderr)
            sidecar = Path(directory) / "execution_module_1.json"
            self.assertTrue(sidecar.is_file())
            sidecar_before = sidecar.read_bytes()
            report = inspect_execution_recovery(path)
            self.assertEqual(report["recovery_status"], "REVIEW_REQUIRED")
            self.assertEqual(report["modules"][0]["artifact_status"], "INTERRUPTED")
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(sidecar.read_bytes(), sidecar_before)
            self.assertEqual(
                [p.name for p in Path(directory).glob("*_module_*.json")],
                ["execution_module_1.json"],
            )

    def test_partial_journal_append_is_detected_and_never_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal = self._started_journal(directory)
            prefix = path.read_bytes()
            source = r"""
import os, sys
from pathlib import Path
from apex_execution import ExecutionJournal, MODULES
path = Path(sys.argv[1])
real_write = os.write
def partial_then_exit(fd, payload):
    amount = max(1, len(payload) // 2)
    real_write(fd, payload[:amount])
    os._exit(73)
os.write = partial_then_exit
journal = ExecutionJournal(path, "crash-test-execution")
journal.finish_module(MODULES[0], "FAILED")
"""
            result = self._child(source, path)
            self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
            damaged = path.read_bytes()
            self.assertTrue(damaged.startswith(prefix))
            self.assertGreater(len(damaged), len(prefix))
            report = inspect_execution_journal(path)
            self.assertFalse(report["valid"])
            self.assertEqual(report["failure_code"], "incomplete_final_event")
            self.assertEqual(report["verified_prefix_bytes"], len(prefix))
            self.assertEqual(report["verified_prefix_sha256"], hashlib.sha256(prefix).hexdigest())
            self.assertEqual(path.read_bytes(), damaged)
            recovery = inspect_execution_recovery(path)
            self.assertEqual(recovery["recovery_status"], "JOURNAL_INVALID")
            self.assertEqual(path.read_bytes(), damaged)


if __name__ == "__main__":
    unittest.main()
